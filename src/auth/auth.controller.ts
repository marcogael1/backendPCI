import {
  Controller,
  Post,
  Body,
  Patch,
  Res,
  Get,
  UnauthorizedException,
  ConflictException,
  BadRequestException,
  Req
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { Response } from 'express';
import { LogService } from '../services/logs.service';
import { Request } from 'express';
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService, private readonly logService: LogService,) { }

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
      await this.logService.createLog(`Inicio de sesión: ${loginDto.email}`);
      return response;
    } catch (error) {
      await this.logService.createLog(`Error de inicio de sesión: ${loginDto.email}`);
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

  @Patch('max-login-attempts')
  updateMaxLoginAttempts(@Body('maxAttempts') maxAttempts: number) {
    this.authService.setMaxLoginAttempts(maxAttempts);
    return { message: `Número máximo de intentos de inicio de sesión actualizado a ${maxAttempts}` };
  }

  @Patch('update-token-expiry')
  async updateTokenExpiry(@Body('newExpiry') newExpiry: number) {
    await this.authService.updateTokenExpiry(newExpiry);
    return {
      message: `Tiempo de expiración del token actualizado a ${newExpiry} minutos`
    };
  }
  @Get('verification-token-expiry')
  async getVerificationTokenExpiry() {
    const expiry = await this.authService.getVerificationTokenExpiry();
    return { expiry };
  }

  @Get('verification-email-message')
  async getVerificationEmailMessage() {
    const message = await this.authService.getVerificationEmailMessage();
    return { message };
  }
  
  @Patch('update-verification-email-message')
  async updateVerificationEmailMessage(@Body('newMessage') newMessage: string) {
    await this.authService.updateVerificationEmailMessage(newMessage);
    return {
      message: `Mensaje de correo de verificación actualizado.`
    };
  }

  @Get('max-login-attempts')
  getMaxLoginAttempts() {
    return { maxAttempts: this.authService.getMaxLoginAttempts() };
  }

  @Post('logout')
  logout(@Res() res: Response) {
    res.clearCookie('jwt', {
      httpOnly: true,
      secure: true,
      sameSite: 'none',
    });
    return res.status(200).json({ message: 'Sesión cerrada correctamente.' });
  }


  @Get('validate-session')
  async validateSession(@Req() req: Request, @Res() res: Response) {
    try {
      const userData = await this.authService.validateSessionjwt(req);
      return res.status(200).json({ message: 'Sesión válida', role: userData.role });
    } catch (error) {
      throw new UnauthorizedException('Sesión inválida.');
    }
  }

}
