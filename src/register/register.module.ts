import { RegisterService } from './register.service';
import { MongooseModule } from '@nestjs/mongoose';
import { RegisterController } from './register.controller';
import { User, UserSchema } from '../schemas/user.schema';
import { EmailService } from '../services/email.service';
import { AppConfigModule } from 'src/services/appconfig.module';
import { Module } from '@nestjs/common';

@Module({
    imports: [MongooseModule.forFeature([{ name: User.name, schema: UserSchema }]),
    AppConfigModule],
    controllers: [RegisterController],
    providers: [
        RegisterService,EmailService],
    exports: [RegisterService],
})
export class RegisterModule { }
