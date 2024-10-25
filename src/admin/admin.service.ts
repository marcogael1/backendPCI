import { Injectable , NotFoundException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Information, InformationDocument } from '../schemas/information.schema';

@Injectable()
export class AdminService {
  constructor(@InjectModel(Information.name) private informationModel: Model<InformationDocument>) {}

  async create(informationData: Partial<Information>): Promise<Information> {
    const lastDocument = await this.informationModel
      .find({ title: informationData.title, isDeleted: false })
      .sort({ version: -1 }) 
      .limit(1)
      .exec();

    let newVersion = '1.0'; 

    if (lastDocument.length > 0) {
      const lastVersion = lastDocument[0].version;
      const versionParts = lastVersion.split('.'); 
      
      const majorVersion = parseInt(versionParts[0], 10) + 1; 
      newVersion = `${majorVersion}.0`; 
    }

    const newDocument = new this.informationModel({
      ...informationData,
      version: newVersion, 
    });

    return await newDocument.save();
  }

  async findAllDeleted(): Promise<Information[]> {
    return await this.informationModel.find({ isDeleted: true }).exec();
  }

  async findAll(): Promise<Information[]> {
    return await this.informationModel.find().exec();
  }

  async findOne(id: string): Promise<Information | null> {
    return await this.informationModel.findById(id).exec();
  }

  async update(id: string, informationData: Partial<Information>): Promise<Information | null> {
    return await this.informationModel.findByIdAndUpdate(id, informationData, {
      new: true,
      useFindAndModify: false,
    }).exec();
  }

  async delete(id: string): Promise<boolean> {
    const result = await this.informationModel.findByIdAndUpdate(id, { isDeleted: true }, { useFindAndModify: false }).exec();
    return result ? true : false;
  }

  async setAsCurrentVersion(documentId: string): Promise<Information | null> {
    const newCurrentDocument = await this.informationModel.findById(documentId).exec();
    if (!newCurrentDocument) {
      throw new NotFoundException(`Documento no encontrado`);
    }
    await this.informationModel.updateMany(
      { title: newCurrentDocument.title, isCurrentVersion: true }, 
      { $set: { isCurrentVersion: false } } 
    ).exec();
    newCurrentDocument.isCurrentVersion = true;
    return await newCurrentDocument.save();
  }
}
