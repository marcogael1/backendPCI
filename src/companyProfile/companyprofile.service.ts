import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { CompanyProfile, CompanyProfileDocument } from '../schemas/companyProfile.schema';

@Injectable()
export class CompanyProfileService {
  constructor(
    @InjectModel(CompanyProfile.name) private companyProfileModel: Model<CompanyProfileDocument>,
  ) {}

  async create(data: any): Promise<CompanyProfile> {
    const createdCompanyProfile = new this.companyProfileModel(data);
    return await createdCompanyProfile.save();
  }

  async findOne(): Promise<CompanyProfile> {
    const profile = await this.companyProfileModel.findOne().exec();
    if (!profile) {
      throw new NotFoundException('Perfil de empresa no encontrado');
    }
    return profile;
  }

  async update(data: any): Promise<CompanyProfile> {
    const existingProfile = await this.companyProfileModel.findOneAndUpdate(
      {}, 
      { $set: data },
      { new: true },
    ).exec();

    if (!existingProfile) {
      throw new NotFoundException('Perfil de empresa no encontrado');
    }
    return existingProfile;
  }

  async delete(): Promise<void> {
    const deletedProfile = await this.companyProfileModel.findOneAndDelete().exec();
    if (!deletedProfile) {
      throw new NotFoundException('Perfil de empresa no encontrado');
    }
  }
}
