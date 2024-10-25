import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export type InformationDocument = Information & Document;

@Schema({ collection: 'information' }) 
export class Information {
  
  @Prop({ required: true })
  title: string; 

  @Prop({ required: true })
  content: string; 

  @Prop({ required: true })
  version: string; 

  @Prop({ type: Date, default: Date.now }) 
  effectiveDate: Date;

  @Prop({ default: false })
  isDeleted: boolean; 

  @Prop({ default: false })
  isCurrentVersion: boolean;
}

export const InformationSchema = SchemaFactory.createForClass(Information);
