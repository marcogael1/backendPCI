import { Controller, Get, Post, Body, Put, Param, Delete } from '@nestjs/common';
import { LogService } from '../services/logs.service';

@Controller('admin/incidents')
export class IncidentsController {
  constructor(private readonly logService: LogService) {}

  @Get('logs')
  async getLogs() {
    const logs = await this.logService.getLogs();
    return logs; 
  }
}