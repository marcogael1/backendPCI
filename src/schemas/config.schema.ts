import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export type AppConfigDocument = AppConfig & Document;

@Schema({ collection: 'config' })  // Se guarda en la colección 'app_config'
export class AppConfig {
  
  @Prop({ required: true, default: 5 })
  maxLoginAttempts: number;

  @Prop({ required: true, default: 'Gracias por registrarte en nuestra aplicación.' })
  verificationEmailMessage: string;

  @Prop({ required: true, default: 15 }) // minutos
  verificationTokenExpiry: number;
}

export const AppConfigSchema = SchemaFactory.createForClass(AppConfig);
