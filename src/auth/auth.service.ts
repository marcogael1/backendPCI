import axios from 'axios';
import * as crypto from 'crypto';
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

@Injectable()
export class AuthService {
  private MAX_LOGIN_ATTEMPTS = 5;
  private LOCK_TIME = 60 * 1000;
  private MFA_VALIDITY_PERIOD = 5 * 60 * 1000;
  private MFA_SECRET = 'secret_mfa_key';
  private RESET_TOKEN_EXPIRATION = 15 * 60 * 1000;
  private PASSWORD_CHANGE_INTERVAL = 24 * 60 * 60 * 1000;
  private tokens = new Map<string, { email: string; expires: Date }>();
  private pendingUsers = new Map<string, { username: string; email: string; password: string }>();

  constructor(@InjectModel(User.name) private userModel: Model<UserDocument>) { }

  private
  transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: 'ironsafe3@gmail.com',
      pass: 'bhiu pxxu gymn xbyo',
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

    const resetLink = `https://pci-tecno.vercel.app/reset-password?token=${token}`;

    const mailOptions = {
      from: 'ironsafe3@gmail.com',
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
      return { message: 'Token enviado. Revisa tu correo.' };
    } catch (error) {
      console.error('Error al enviar correo:', error);
      throw new ConflictException('No se pudo enviar el token.');
    }
  }

  async sendVerificationEmail(username: string, email: string, password: string): Promise<void> {
    const verificationToken = randomBytes(32).toString('hex');
    this.pendingUsers.set(verificationToken, { username, email, password });

    const verificationLink = `https://pci-tecno.vercel.app/verify-email?token=${verificationToken}`;
    const mailOptions = {
      from: 'ironsafe3@gmail.com',
      to: email,
      subject: 'Verificación de cuenta',
      html: `
    <div style="font-family: Arial, sans-serif; text-align: center; color: #333; padding: 20px;">
      <h1 style="color: #1a73e8;">¡Hola, ${username}!</h1>
      <p style="font-size: 16px; color: #333;">
        Gracias por registrarte en nuestra aplicación. Por favor, confirma tu cuenta haciendo clic en el siguiente botón:
      </p>
      <a href="${verificationLink}" 
         style="background-color: #1a73e8; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block; font-size: 16px;">
        Verificar cuenta
      </a>
      <p style="font-size: 14px; margin-top: 20px; color: #666;">
        Si no puedes hacer clic en el botón, copia y pega el siguiente enlace en tu navegador:
      </p>
      <p style="font-size: 14px; color: #1a73e8;"><a href="${verificationLink}" style="color: #1a73e8;">${verificationLink}</a></p>
      <p style="font-size: 14px; color: #666; margin-top: 20px;">
        Este enlace es válido solo por <strong>15 minutos</strong>. Si no solicitaste esta verificación, puedes ignorar este correo.
      </p>
      <hr style="border: none; border-top: 1px solid #eee; margin: 40px 0;" />
      <p style="font-size: 12px; color: #999;">
        Saludos,<br>El equipo de Tu App
      </p>
    </div>
  `,
    };

    try {
      await this.transporter.sendMail(mailOptions);
    } catch (error) {
      console.error('Error al enviar correo:', error);
      throw new ConflictException('No se pudo enviar el correo de verificación.');
    }
  }

  async verifyEmailToken(token: string): Promise<any> {
    console.log('Tokens guardados:', this.pendingUsers);
    const pendingUser = this.pendingUsers.get(token);
    if (!pendingUser) {
      throw new BadRequestException('Token de verificación inválido o expirado.');
    }
    const { username, email, password } = pendingUser;
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new this.userModel({
      username,
      email,
      password: hashedPassword,
      isVerified: true,
    });
    await newUser.save();
    this.pendingUsers.delete(token);
    return { message: 'Cuenta verificada y usuario registrado con éxito.' };
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
      throw new ConflictException('Solo puedes cambiar la contraseña una vez cada 24 horas.');
    }

    user.password = await bcrypt.hash(newPassword, 10);
    user.lastPasswordChange = now;
    user.resetToken = null;
    user.resetTokenExpires = null;
    user.sessionId = null;
    await user.save();

    return { message: 'Contraseña cambiada con éxito.' };
  }

  async loginUser(email: string, password: string, res: Response): Promise<any> {
    const user = await this.userModel.findOne({ email }).exec();
    if (!user) throw new UnauthorizedException('Credenciales incorrectas');

    if (user.lockUntil && user.lockUntil > new Date()) {
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

      const sessionId = await this.generateSessionId(user);
      res.cookie('sessionId', sessionId, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
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


  async verifyMfa(email: string, code: string, token: string, res: Response): Promise<any> {
    const payload = this.verifyMfaToken(token);
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

    const sessionId = await this.generateSessionId(user);

    res.cookie('sessionId', sessionId, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
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

  private async incrementLoginAttempts(user: UserDocument) {
    user.loginAttempts += 1;
    if (user.loginAttempts >= this.MAX_LOGIN_ATTEMPTS) {
      user.lockUntil = new Date(Date.now() + this.LOCK_TIME);
    }
    await user.save();
  }

  private async sendMfaCode(email: string, code: string) {
    const mailOptions = {
      from: 'ironsafe3@gmail.com',
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

  private async isPasswordCompromised(password: string): Promise<boolean> {
    const sha1Hash = crypto.createHash('sha1').update(password).digest('hex').toUpperCase();
    const prefix = sha1Hash.substring(0, 5);
    const suffix = sha1Hash.substring(5);

    try {
      const response = await axios.get(`https://api.pwnedpasswords.com/range/${prefix}`);
      return response.data.split('\n').some((line) => {
        const [hashSuffix] = line.split(':');
        return hashSuffix.trim() === suffix;
      });
    } catch (error) {
      console.error('Error verificando contraseña:', error);
      throw new ConflictException('Error al verificar la contraseña.');
    }
  }

  async registerUser(username: string, email: string, password: string): Promise<any> {
    if (!/^[a-zA-Z0-9_]+$/.test(username)) {
      throw new BadRequestException('El nombre de usuario contiene caracteres no permitidos.');
    }

    if (!/^[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};':",.<>/?|]*$/.test(password)) {
      throw new BadRequestException('La contraseña contiene caracteres no permitidos.');
    }

    const existingUser = await this.userModel.findOne({ email }).exec();
    if (existingUser) {
      throw new ConflictException('El correo ya está registrado.');
    }

    const isCompromised = await this.isPasswordCompromised(password);
    if (isCompromised) {
      return { message: 'Esta contraseña está expuesta en brechas de seguridad. Por favor usa otra.' };
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new this.userModel({
      username,
      email,
      password: hashedPassword,
      type: 'cliente'
    });

    await newUser.save();
    return { message: 'Registro exitoso' };
  }
}
