import {
  Controller,
  Post,
  Body,
  Patch,
  Res,
  Query,
  UnauthorizedException,
  ConflictException,
  HttpException,
  HttpStatus,
  BadRequestException
} from '@nestjs/common';
import { AuthService } from './auth.service';
import axios from 'axios';
import { Response } from 'express';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) { }

  @Post('login')
  async login(
    @Body() loginDto: { email: string; password: string },
    @Res({ passthrough: true }) res: Response,
  ) {
    try {
      const response = await this.authService.loginUser(
        loginDto.email,
        loginDto.password,
        res,
      );
      return response;
    } catch (error) {
      throw new UnauthorizedException(error.message || 'Error al iniciar sesión.');
    }
  }

  @Post('verify-mfa')
  async verifyMfa(
    @Body() verifyMfaDto: { email: string; code: string; token: string },
    @Res({ passthrough: true }) res: Response
  ) {
    try {
      const response = await this.authService.verifyMfa(
        verifyMfaDto.email,
        verifyMfaDto.code,
        verifyMfaDto.token,
        res
      );
      return response;
    } catch (error) {
      throw new UnauthorizedException(error.message || 'Error al verificar el código MFA.');
    }
  }

  @Post('register')
  async register(
    @Body() registerDto: { username: string; email: string; password: string; recaptchaToken: string }
  ) {
    const { username, email, password, recaptchaToken } = registerDto;
    const isRecaptchaValid = await this.verifyRecaptcha(recaptchaToken);
    if (!isRecaptchaValid) {
      throw new HttpException('reCAPTCHA no válido', HttpStatus.FORBIDDEN);
    }

    try {
      await this.authService.sendVerificationEmail(username, email, password);
      return {
        message: 'Registro iniciado. Revisa tu correo para verificar tu cuenta.',
      };
    } catch (error) {
      throw new HttpException('No se pudo iniciar el registro.', HttpStatus.CONFLICT);
    }
  }

  @Post('verify-email')
  async verifyEmail(@Body('token') token: string): Promise<any> {
    console.log('Token recibido para verificación:', token);
    return await this.authService.verifyEmailToken(token);
  }



  private async verifyRecaptcha(token: string): Promise<boolean> {
    const secretKey = '6LdUFV8qAAAAAMxD51fEspUDsvkBTbbVR9x3fuOn';
    const url = `https://www.google.com/recaptcha/api/siteverify?secret=${secretKey}&response=${token}`;

    try {
      const response = await axios.post(url);
      return response.data.success;
    } catch (error) {
      console.error('Error verificando reCAPTCHA:', error);
      return false;
    }
  }


  @Post('validate-token')
  async validateToken(@Body('token') token: string): Promise<any> {
    const user = await this.authService.getUserByResetToken(token);

    if (!user) {
      throw new BadRequestException('Token inválido o expirado.');
    }

    return { message: 'Token válido.' };
  }


  @Post('request-reset-password')
  async sendResetPasswordToken(@Body('email') email: string): Promise<any> {
    try {
      return await this.authService.sendResetPasswordToken(email);
    } catch (error) {
      throw new BadRequestException(
        error.message || 'Error al enviar el token de restablecimiento.'
      );
    }
  }

  @Patch('reset-password')
  async changePassword(
    @Body('token') token: string,
    @Body('currentPassword') currentPassword: string,
    @Body('newPassword') newPassword: string
  ): Promise<any> {
    try {
      return await this.authService.changePassword(
        token,
        currentPassword,
        newPassword
      );
    } catch (error) {
      if (error instanceof UnauthorizedException) {
        throw new UnauthorizedException('Contraseña actual incorrecta.');
      }
      if (error instanceof ConflictException) {
        throw new ConflictException(
          'Solo puedes cambiar la contraseña una vez cada 24 horas.'
        );
      }
      throw new BadRequestException('Error al cambiar la contraseña.');
    }
  }

}
