import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export type LogDocument = Log & Document;

@Schema({ collection: 'logs' })  
export class Log {
  @Prop({ required: true })
  dateTime: string; 

  @Prop({ required: true })
  content: string;  
}

export const LogSchema = SchemaFactory.createForClass(Log);
