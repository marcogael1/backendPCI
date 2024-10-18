import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Information, InformationDocument } from '../schemas/information.schema';

@Injectable()
export class AdminService {
  constructor(
    @InjectModel(Information.name) private informationModel: Model<InformationDocument>,
  ) {}
  async create(data: any): Promise<Information> {
    const newInfo = new this.informationModel(data);
    return newInfo.save();
  }

  async findAll(): Promise<Information[]> {
    return this.informationModel.find().exec();
  }

  async findOne(id: string): Promise<Information> {
    const information = await this.informationModel.findById(id).exec();
    if (!information) {
      throw new NotFoundException(`Information with ID ${id} not found`);
    }
    return information;
  }

  async update(id: string, data: any): Promise<Information> {
    const updatedInfo = await this.informationModel.findByIdAndUpdate(id, data, {
      new: true,
    }).exec();
    if (!updatedInfo) {
      throw new NotFoundException(`Information with ID ${id} not found`);
    }
    return updatedInfo;
  }

  async remove(id: string): Promise<void> {
    const result = await this.informationModel.findByIdAndDelete(id).exec();
    if (!result) {
      throw new NotFoundException(`Information with ID ${id} not found`);
    }
  }
}
