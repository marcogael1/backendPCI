import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { MongooseModule } from '@nestjs/mongoose';
import { User, UserSchema } from '../schemas/user.schema';
import { JwtService } from '@nestjs/jwt';
import { LogsModule } from '../services/logs.module'; 
import { AppConfigModule } from 'src/services/appconfig.module';
@Module({
  imports: [
    MongooseModule.forFeature([{ name: User.name, schema: UserSchema }]), 
    LogsModule,
    AppConfigModule
  ],
  controllers: [AuthController],
  providers: [
    AuthService,JwtService
  ],
  exports: [AuthService],
})
export class AuthModule {}
