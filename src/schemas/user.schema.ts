import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export type UserDocument = User & Document;

@Schema()
export class User {
  @Prop({ required: true })
  username: string;

  @Prop({ required: true, unique: true })
  email: string;

  @Prop({ required: true })
  password: string;

  @Prop({ default: 'cliente' })
  type: string;

  @Prop({ default: 0 })
  loginAttempts: number;

  @Prop({ default: null })
  lockUntil: Date | null;

  @Prop({ default: null })
  mfaCode: string | null;

  @Prop({ default: null })
  mfaExpires: Date | null;

  @Prop({ default: null })
  resetToken: string | null;

  @Prop({ default: null })
  resetTokenExpires: Date | null;

  @Prop({ default: null })
  lastPasswordChange: Date | null;

  @Prop({ default: null })
  sessionId: string | null;

  @Prop({ default: false })
  isVerified: boolean;
}

export const UserSchema = SchemaFactory.createForClass(User);
