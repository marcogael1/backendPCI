import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export type CompanyProfileDocument = CompanyProfile & Document;

@Schema({ collection: 'companyProfile' }) 
export class CompanyProfile {
  @Prop({
    type: {
      facebook: { type: String, required: false },
      twitter: { type: String, required: false },
      linkedin: { type: String, required: false },
      instagram: { type: String, required: false },
    },
  })
  socialMedia: {
    facebook: string;
    twitter: string;
    linkedin: string;
    instagram: string;
  };

  @Prop({ required: false, maxlength: 100 })
  slogan: string;

  @Prop({ type: String, required: false })
  logo: string;

  @Prop({ required: false })
  pageTitle: string;

  @Prop({
    type: {
      address: { type: String, required: false },
      email: { type: String, required: false },
      phone: { type: String, required: false },
    },
  })
  contact: {
    address: string;
    email: string;
    phone: string;
  };

  @Prop({
    type: {
      dateModified: { type: Date, default: Date.now },
    },
  })
  audit: {
    dateModified: Date;
  };

}

export const CompanyProfileSchema = SchemaFactory.createForClass(CompanyProfile);
