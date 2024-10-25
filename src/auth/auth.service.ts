import { randomBytes, randomUUID } from 'crypto';
import { Response } from 'express';
import * as bcrypt from 'bcrypt';
import * as jwt from 'jsonwebtoken';
import * as nodemailer from 'nodemailer';
import {
  Injectable,
  ConflictException,
  UnauthorizedException,
  BadRequestException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User, UserDocument } from '../schemas/user.schema';
import { LogService } from '../services/logs.service';
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';
import { AppConfigService } from '../services/config.service';
@Injectable()
export class AuthService {
  private MAX_LOGIN_ATTEMPTS: number;
  private LOCK_TIME = 60 * 1000;
  private MFA_VALIDITY_PERIOD = 60 * 60 * 1000;
  private MFA_SECRET = 'secret_mfa_key';
  private BLOCK_DAYS_THRESHOLD = 7;
  private MAX_BLOCKS_IN_PERIOD = 3;

  constructor(@InjectModel(User.name) private userModel: Model<UserDocument>, private readonly logService: LogService, private jwtService: JwtService, private readonly appConfigService: AppConfigService) { this.loadConfigFromDatabase(); }


  private async loadConfigFromDatabase() {
    const config = await this.appConfigService.getAllConfig();
    this.MAX_LOGIN_ATTEMPTS = config.maxLoginAttempts || 5; 
    this.MFA_VALIDITY_PERIOD = config.verificationTokenExpiry || this.MFA_VALIDITY_PERIOD;
  }

  transporter = nodemailer.createTransport({
    service: process.env.EMAIL_SERVICE,
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });

  async findUserBySessionId(sessionId: string): Promise<UserDocument | null> {
    return this.userModel.findOne({ sessionId }).exec();
  }


  async sendResetPasswordToken(email: string): Promise<any> {
    const user = await this.userModel.findOne({ email }).exec();
    if (!user) throw new BadRequestException('Usuario no encontrado.');

    const token = randomBytes(32).toString('hex');
    const expires = new Date(Date.now() + 15 * 60 * 1000);

    user.resetToken = token;
    user.resetTokenExpires = expires;
    await user.save();
    const frontendUrl = process.env.FRONTEND_URL;
    const resetLink = `${frontendUrl}/reset-password?token=${token}`;

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Restablecimiento de contraseña',
      html: `
        <div style="font-family: Arial, sans-serif; text-align: center; color: #333;">
          <h1 style="color: #1a73e8;">¡Hola!</h1>
          <p>Se solicitó un restablecimiento de contraseña para tu cuenta <strong>${email}</strong>.</p>
          <p>Haz clic en el siguiente botón para cambiar tu contraseña:</p>
          <a href="${resetLink}" 
             style="background-color: #1a73e8; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block;">
            Cambiar contraseña
          </a>
          <p style="margin-top: 20px;">Si no realizaste esta solicitud, puedes ignorar este mensaje.</p>
          <p>Este enlace es válido solo por <strong>15 minutos</strong>.</p>
          <hr />
          <p>Si tienes problemas con el botón anterior, copia y pega el siguiente enlace en tu navegador:</p>
          <p><a href="${resetLink}">${resetLink}</a></p>
          <p>Saludos,<br>Tu App</p>
        </div>
      `,
    };

    try {
      await this.transporter.sendMail(mailOptions);
      await this.logService.createLog(`Token de restablecimiento enviado a: ${email}`);
      return { message: 'Token enviado. Revisa tu correo.' };
    } catch (error) {
      await this.logService.createLog(`Error al enviar token a ${email}: ${error.message}`);
      console.error('Error al enviar correo:', error);
      throw new ConflictException('No se pudo enviar el token.');
    }
  }


  async getUserByResetToken(token: string): Promise<UserDocument | null> {
    const user = await this.userModel.findOne({
      resetToken: token,
      resetTokenExpires: { $gt: new Date() },
    }).exec();
    return user;
  }


  private async generateSessionId(user: UserDocument): Promise<string> {
    const sessionId = randomUUID();
    user.sessionId = sessionId;
    await user.save();
    return sessionId;
  }


  async revokeSession(userId: string): Promise<any> {
    const user = await this.userModel.findById(userId).exec();
    if (!user) throw new BadRequestException('Usuario no encontrado.');

    user.sessionId = null;
    await user.save();
    return { message: 'Sesión revocada exitosamente.' };
  }


  async changePassword(
    token: string,
    currentPassword: string,
    newPassword: string
  ): Promise<any> {
    const user = await this.userModel.findOne({ resetToken: token }).exec();

    if (!user || user.resetTokenExpires < new Date()) {
      throw new BadRequestException('Token inválido o expirado.');
    }

    const isPasswordValid = await bcrypt.compare(currentPassword, user.password);
    if (!isPasswordValid) {
      throw new UnauthorizedException('Contraseña actual incorrecta.');
    }

    const lastPasswordChange = user.lastPasswordChange ?? new Date(0);
    const now = new Date();

    if (now.getTime() - lastPasswordChange.getTime() < 24 * 60 * 60 * 1000) {
      await this.logService.createLog(`Error: Intento de cambio de contraseña para ${user.email} antes de las 24 horas.`);
      throw new ConflictException('Solo puedes cambiar la contraseña una vez cada 24 horas.');
    }

    user.password = await bcrypt.hash(newPassword, 10);
    user.lastPasswordChange = now;
    user.resetToken = null;
    user.resetTokenExpires = null;
    user.sessionId = null;
    await user.save();
    await this.logService.createLog(`Contraseña cambiada con éxito para ${user.email}`);
    return { message: 'Contraseña cambiada con éxito.' };
  }

  async loginUser(email: string, password: string, res: Response): Promise<any> {
    const user = await this.userModel.findOne({ email }).exec();
    if (!user) throw new UnauthorizedException('Credenciales incorrectas');

    if (!user.isVerified) {
        throw new UnauthorizedException('Tu cuenta no ha sido verificada. Por favor, revisa tu correo para verificarla.');
    }

    if (user.lockUntil && user.lockUntil > new Date()) {
        await this.logService.createLog(`Intento de inicio de sesión con cuenta bloqueada: ${email}`);
        throw new UnauthorizedException('Cuenta bloqueada. Inténtalo más tarde.');
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
        await this.incrementLoginAttempts(user);
        throw new UnauthorizedException('Credenciales incorrectas');
    }

    user.loginAttempts = 0;
    user.lockUntil = null;

    const now = new Date();
    const lastMfaTime = user.mfaExpires ?? new Date(0);

    if (user.mfaCode) {
        const mfaToken = this.generateMfaToken(email);
        return {
            message: 'Código MFA pendiente. Verifica tu correo.',
            mfaRequired: true,
            mfaToken,
            userType: user.type,
        };
    }

    if (now.getTime() - lastMfaTime.getTime() < this.MFA_VALIDITY_PERIOD) {
        await user.save();

        const token = jwt.sign({ userId: user._id, role: user.type }, process.env.JWT_SECRET, {
            expiresIn: '1h',
        });

        res.cookie('jwt', token, {
            httpOnly: true,
            secure: true,
            sameSite: 'none',
            maxAge: 60 * 60 * 1000,
        });

        return { message: 'Inicio de sesión sin necesidad de MFA.', userType: user.type };
    }

    const mfaCode = Math.floor(100000 + Math.random() * 900000).toString();
    user.mfaCode = mfaCode;
    user.mfaExpires = new Date(now.getTime() + this.MFA_VALIDITY_PERIOD);
    await user.save();

    const mfaToken = this.generateMfaToken(email);
    await this.sendMfaCode(email, mfaCode);

    return {
        message: 'Código MFA enviado. Verifica tu correo.',
        mfaRequired: true,
        mfaToken,
        userType: user.type,
    };
}



  async verifyMfa(email: string, code: string, mfaToken: string, res: Response): Promise<any> {
    const payload = this.verifyMfaToken(mfaToken);
    if (payload.email !== email) {
      throw new UnauthorizedException('Token MFA inválido.');
    }

    const user = await this.userModel.findOne({ email }).exec();
    if (!user || user.mfaCode !== code) {
      throw new UnauthorizedException('Código MFA inválido o expirado.');
    }

    user.mfaCode = null;
    user.mfaExpires = new Date();
    await user.save();

    const token = jwt.sign({ userId: user._id, role: user.type }, process.env.JWT_SECRET, {
      expiresIn: '1h',
    });

    res.cookie('jwt', token, {
      httpOnly: true,
      secure: true,
      sameSite: 'none',
      maxAge: 60 * 60 * 1000,
    });
    return { message: 'Autenticación completa', userType: user.type };
  }


  private generateMfaToken(email: string): string {
    const payload = { email };
    return jwt.sign(payload, this.MFA_SECRET, { expiresIn: '5m' });
  }

  private verifyMfaToken(token: string): any {
    try {
      return jwt.verify(token, this.MFA_SECRET);
    } catch (error) {
      throw new UnauthorizedException('Token MFA inválido o expirado.');
    }
  }


  private async checkBlockedHistory(user: UserDocument): Promise<boolean> {
    const now = new Date();
    const thresholdDate = new Date(now.getTime() - this.BLOCK_DAYS_THRESHOLD * 24 * 60 * 60 * 1000);
    const recentBlocks = user.blockedHistory.filter(block => block.date > thresholdDate);
    if (recentBlocks.length >= this.MAX_BLOCKS_IN_PERIOD) {
      await this.logService.createLog(`Usuario ${user.email} ha sido bloqueado más de ${this.MAX_BLOCKS_IN_PERIOD} veces en los últimos ${this.BLOCK_DAYS_THRESHOLD} días.`);
      user.lockUntil = new Date(Date.now() + this.LOCK_TIME * 10);
      await user.save();
      return true;
    }
    return false;
  }

  private async incrementLoginAttempts(user: UserDocument) {
    user.loginAttempts += 1;

    if (user.loginAttempts >= this.MAX_LOGIN_ATTEMPTS) {
      user.lockUntil = new Date(Date.now() + this.LOCK_TIME);
      user.blockedHistory.push({ date: new Date() });
      const isBlocked = await this.checkBlockedHistory(user);
      if (isBlocked) {
        throw new UnauthorizedException('Cuenta bloqueada por múltiples intentos fallidos.');
      }
      await this.logService.createLog(`Cuenta bloqueada: ${user.email}`);
    }

    await user.save();
  }

  private async sendMfaCode(email: string, code: string) {
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Tu código de autenticación MFA',
      text: `Tu código MFA es: ${code}`,
    };

    try {
      await this.transporter.sendMail(mailOptions);
    } catch (error) {
      console.error('Error al enviar correo:', error);
      throw new ConflictException('No se pudo enviar el código MFA.');
    }
  }

  getMaxLoginAttempts(): number {
    return this.MAX_LOGIN_ATTEMPTS;
  }

  async setMaxLoginAttempts(newLimit: number): Promise<void> {
    await this.appConfigService.updateMaxLoginAttempts(newLimit);
    this.MAX_LOGIN_ATTEMPTS = newLimit;
    await this.logService.createLog(`Máximo de intentos de inicio de sesión actualizado a ${newLimit}`);
  }

  async updateTokenExpiry(newExpiry: number): Promise<void> {
    await this.appConfigService.updateVerificationTokenExpiry(newExpiry);
    this.MFA_VALIDITY_PERIOD = newExpiry * 60 * 1000;
    await this.logService.createLog(`Tiempo de expiración del token actualizado a ${newExpiry} minutos`);
  }

  async updateVerificationEmailMessage(newMessage: string): Promise<void> {
    await this.appConfigService.updateVerificationEmailMessage(newMessage);
    await this.logService.createLog(`Mensaje de correo de verificación actualizado: ${newMessage}`);
  }

  async getVerificationTokenExpiry(): Promise<number> {
    const config = await this.appConfigService.getAllConfig();
    return config.verificationTokenExpiry;
  }

  async getVerificationEmailMessage(): Promise<string> {
    const config = await this.appConfigService.getAllConfig();
    return config.verificationEmailMessage;
  }
  async validateSession(sessionId: string): Promise<boolean> {
    const user = await this.userModel.findOne({ sessionId }).exec();
    if (!user) {
      return false;
    }
    return true;
  }

  async validateSessionjwt(req: Request): Promise<any> {
    const token = req.cookies['jwt'];

    if (!token) {
      throw new UnauthorizedException('No hay token en la cookie.');
    }

    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      return decoded;
    } catch (err) {
      throw new UnauthorizedException('Token inválido o expirado.');
    }
  }
}
