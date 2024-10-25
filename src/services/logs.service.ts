import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Log, LogDocument } from '../schemas/logs.schema';  

@Injectable()
export class LogService {
  constructor(@InjectModel(Log.name) private logModel: Model<LogDocument>) {}

  async createLog(content: string): Promise<Log> {
    const currentDateTime = new Date().toLocaleString('es-MX', {
      timeZone: 'America/Mexico_City', 
    });

    const newLog = new this.logModel({ dateTime: currentDateTime, content });
    return await newLog.save();
  }

  async getLogs(): Promise<Log[]> {
    return await this.logModel.find().sort({ dateTime: -1 }).exec();
  }
}
