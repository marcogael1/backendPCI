import axios from 'axios';
import {
    Controller,
    Post,
    Body,
    HttpException,
    HttpStatus,
    Patch,
    Get
} from '@nestjs/common';
import { RegisterService } from './register.service';
import { EmailService } from '../services/email.service';

@Controller('register')
export class RegisterController {
    constructor(private readonly registerService: RegisterService, private readonly emailService: EmailService) { }

    @Post('Sign-up')
    async register(
        @Body() registerDto: { username: string; email: string; password: string; recaptchaToken: string }
    ) {
        const { username, email, password, recaptchaToken } = registerDto;

        const emailExists = await this.registerService.checkIfEmailExists(email);
        if (emailExists) {
            throw new HttpException('El usuario con este correo ya existe.', HttpStatus.CONFLICT);
        }
        const isRecaptchaValid = await this.verifyRecaptcha(recaptchaToken);
        if (!isRecaptchaValid) {
            throw new HttpException('reCAPTCHA no válido', HttpStatus.FORBIDDEN);
        }

        try {
            await this.registerService.sendVerificationEmail(username, email, password);
            return {
                message: 'Registro iniciado. Revisa tu correo para verificar tu cuenta.',
            };
        } catch (error) {
            throw new HttpException(error.message || 'No se pudo iniciar el registro.', HttpStatus.CONFLICT);
        }
    }


    @Post('verify-email')
    async verifyEmail(@Body('token') token: string): Promise<any> {
        return await this.registerService.verifyEmailToken(token);
    }

    private async verifyRecaptcha(token: string): Promise<boolean> {
        const secretKey = process.env.SECRET_KEY;
        const url = `https://www.google.com/recaptcha/api/siteverify?secret=${secretKey}&response=${token}`;

        try {
            const response = await axios.post(url);
            return response.data.success;
        } catch (error) {
            console.error('Error verificando reCAPTCHA:', error);
            return false;
        }
    }

    @Get('content')
    getEmailContent() {
        return { content: this.emailService.loadEmailData() };
    }

    @Patch('content')
    updateEmailContent(@Body('content') content: string) {
        const emailData = this.emailService.loadEmailData();
        emailData.verificationEmailMessage = content;
        this.emailService.saveEmailData(emailData);

        return { message: 'Contenido del correo actualizado exitosamente.' };
    }

    @Patch('update-token-expiry')
    updateTokenExpiry(@Body('expiry') expiry: number) {
        const emailData = this.emailService.loadEmailData();
        emailData.verificationTokenExpiry = expiry;
        this.emailService.saveEmailData(emailData);

        return { message: `El tiempo de expiración del token se ha actualizado a ${expiry} minutos.` };
    }

    @Get('token-expiry')
    getTokenExpiry() {
        const emailData = this.emailService.loadEmailData();
        return { expiry: emailData.verificationTokenExpiry || 15 };
    }

}
