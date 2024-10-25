import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { AppConfigService } from './config.service';
import { AppConfig, AppConfigSchema } from '../schemas/config.schema';

@Module({
  imports: [
    MongooseModule.forFeature([{ name: AppConfig.name, schema: AppConfigSchema }]), 
  ],
  providers: [AppConfigService],
  exports: [AppConfigService],  
})
export class AppConfigModule {}
