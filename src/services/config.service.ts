import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { AppConfig, AppConfigDocument } from '../schemas/config.schema';

@Injectable()
export class AppConfigService {
  constructor(@InjectModel(AppConfig.name) private appConfigModel: Model<AppConfigDocument>) {}

  async getAllConfig(): Promise<AppConfig> {
    const config = await this.appConfigModel.findOne().exec();
    if (!config) {
      throw new NotFoundException('Configuración no encontrada');
    }
    return config;
  }

  async updateMaxLoginAttempts(newAttempts: number): Promise<AppConfig> {
    const config = await this.appConfigModel.findOneAndUpdate({}, { maxLoginAttempts: newAttempts }, { new: true }).exec();
    if (!config) {
      throw new NotFoundException('Configuración no encontrada');
    }
    return config;
  }

  async updateVerificationEmailMessage(newMessage: string): Promise<AppConfig> {
    const config = await this.appConfigModel.findOneAndUpdate({}, { verificationEmailMessage: newMessage }, { new: true }).exec();
    if (!config) {
      throw new NotFoundException('Configuración no encontrada');
    }
    return config;
  }

  async updateVerificationTokenExpiry(newExpiry: number): Promise<AppConfig> {
    const config = await this.appConfigModel.findOneAndUpdate({}, { verificationTokenExpiry: newExpiry }, { new: true }).exec();
    if (!config) {
      throw new NotFoundException('Configuración no encontrada');
    }
    return config;
  }
}
