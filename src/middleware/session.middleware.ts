import { Injectable, NestMiddleware, UnauthorizedException } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { AuthService } from '../auth/auth.service';

@Injectable()
export class SessionMiddleware implements NestMiddleware {
  constructor(private readonly authService: AuthService) {}

  async use(req: Request, res: Response, next: NextFunction) {
    const sessionId = req.cookies['sessionId'];
    if (!sessionId) {
      return res.status(401).json({ message: 'No hay sesión activa.' });
    }
    const user = await this.authService.findUserBySessionId(sessionId);
    if (!user) {
      return res.status(401).json({ message: 'Sesión inválida.' });
    }
    next();
  }
  
}
