import { Injectable, ConflictException, BadRequestException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import axios from 'axios';
import * as crypto from 'crypto';
import { Model } from 'mongoose';
import { User, UserDocument } from '../schemas/user.schema';
import { randomBytes } from 'crypto';
import * as bcrypt from 'bcrypt';
import * as nodemailer from 'nodemailer';
import { EmailService } from '../services/email.service';
import { AppConfigService } from '../services/config.service';
@Injectable()
export class RegisterService {
    private pendingUsers = new Map<string, { username: string; email: string; password: string, tokenExpiryDate: Date }>();

    constructor(@InjectModel(User.name) private userModel: Model<UserDocument>, private readonly emailService: EmailService, private readonly appConfigService: AppConfigService) { }


    transporter = nodemailer.createTransport({
        service: process.env.EMAIL_SERVICE,
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS,
        },
    });

    async checkIfEmailExists(email: string): Promise<boolean> {
        const user = await this.userModel.findOne({ email }).exec();
        return !!user;
    }

    async sendVerificationEmail(username: string, email: string, password: string): Promise<void> {
      const isCompromised = await this.isPasswordCompromised(password);
      if (isCompromised) {
        throw new ConflictException('La contraseña ingresada ha sido comprometida en filtraciones previas. Por favor, elige una contraseña diferente.');
      }
    
      const verificationToken = randomBytes(32).toString('hex');
      const config = await this.appConfigService.getAllConfig();
      const tokenExpiryMinutes = config.verificationTokenExpiry || 15;
      const tokenExpiryDate = new Date(Date.now() + tokenExpiryMinutes * 60 * 1000);
    
      const hashedPassword = await bcrypt.hash(password, 10);
      let user = await this.userModel.findOne({ email }).exec();
      if (!user) {
        user = new this.userModel({
          username,
          email,
          password: hashedPassword,
          verificationToken,
          verificationTokenExpiry: tokenExpiryDate,
          isVerified: false
        });
      } else {
        user.verificationToken = verificationToken;
        user.verificationTokenExpiry = tokenExpiryDate;
      }
      await user.save();
    
      const frontendUrl = process.env.FRONTEND_URL;
      const verificationLink = `${frontendUrl}/verify-email?token=${verificationToken}`;
      const emailMessage = config.verificationEmailMessage || "Gracias por registrarte en nuestra aplicación.";
    
      const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Verificación de cuenta',
        html: `
          <div style="font-family: Arial, sans-serif; text-align: center; color: #333; padding: 20px;">
            <h1 style="color: #1a73e8;">¡Hola, ${username}!</h1>
            <p style="font-size: 16px; color: #333;">
              ${emailMessage}
            </p>
            <a href="${verificationLink}" 
               style="background-color: #1a73e8; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block; font-size: 16px;">
              Verificar cuenta
            </a>
            <p style="font-size: 14px; margin-top: 20px; color: #666;">
              Si no puedes hacer clic en el botón, copia y pega el siguiente enlace en tu navegador:
            </p>
            <p style="font-size: 14px; color: #1a73e8;">
              <a href="${verificationLink}" style="color: #1a73e8;">${verificationLink}</a>
            </p>
            <p style="font-size: 14px; color: #666; margin-top: 20px;">
              Este enlace es válido solo por <strong>${tokenExpiryMinutes} minutos</strong>. Si no solicitaste esta verificación, puedes ignorar este correo.
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
      const user = await this.userModel.findOne({ verificationToken: token }).exec();
    
      if (!user) {
        throw new BadRequestException('Token de verificación inválido o expirado.');
      }
    
      if (new Date() > user.verificationTokenExpiry) {
        throw new BadRequestException('Token de verificación ha expirado.');
      }
    
      user.isVerified = true;
      user.verificationToken = null; 
      user.verificationTokenExpiry = null;
      await user.save();
    
      return { message: 'Cuenta verificada y usuario registrado con éxito.' };
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
}
