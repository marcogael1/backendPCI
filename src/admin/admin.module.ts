import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { AdminService } from './admin.service';
import { AdminController } from './admin.controller';
import { Information, InformationSchema } from '../schemas/information.schema';

@Module({
  imports: [MongooseModule.forFeature([{ name: Information.name, schema: InformationSchema }])],
  controllers: [AdminController],
  providers: [AdminService],
  exports: [AdminController],
})
export class AdminModule {}
