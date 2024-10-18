import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export type InformationDocument = Information & Document;

@Schema()
export class Information {
  @Prop({ required: true })
  type: string;

  @Prop({ required: true, type: String })
  description: string;
}

export const InformationSchema = SchemaFactory.createForClass(Information);
