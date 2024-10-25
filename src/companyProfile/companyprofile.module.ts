import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { CompanyProfileService } from './companyprofile.service';
import { CompanyProfileController } from './companyprofile.controller';
import { CompanyProfile, CompanyProfileSchema } from '../schemas/companyProfile.schema';

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: CompanyProfile.name, schema: CompanyProfileSchema },
    ]),
  ],
  controllers: [CompanyProfileController],
  providers: [CompanyProfileService],
  exports: [CompanyProfileService],  
})
export class CompanyProfileModule {}
