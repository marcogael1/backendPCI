import { Controller, Get, Post, Put, Delete, Param, Body, NotFoundException } from '@nestjs/common';
import { AdminService } from './admin.service';
import { Information } from '../schemas/information.schema';

@Controller('admin')
export class AdminController {
  constructor(private readonly adminService: AdminService) { }

  @Post('information')
  async create(@Body() informationData: Partial<Information>) {
    return await this.adminService.create(informationData);
  }

  @Get('information')
  async findAll() {
    return await this.adminService.findAll();
  }

  @Get('deleted-documents')
  async findAllDeleted(): Promise<Information[]> {
    return await this.adminService.findAllDeleted();
  }

  @Get('information/:id')
  async findOne(@Param('id') id: string) {
    const document = await this.adminService.findOne(id);
    if (!document) {
      throw new NotFoundException(`Documento no encontrado`);
    }
    return document;
  }

  @Put('information/:id')
  async update(@Param('id') id: string, @Body() informationData: Partial<Information>) {
    const updatedDocument = await this.adminService.update(id, informationData);
    if (!updatedDocument) {
      throw new NotFoundException(`Documento no encontrado`);
    }
    return updatedDocument;
  }

  @Delete('information/:id')
  async delete(@Param('id') id: string) {
    const deleted = await this.adminService.delete(id);
    if (!deleted) {
      throw new NotFoundException(`Documento no encontrado`);
    }
    return { message: `El documento ha sido eliminado` };
  }

  @Put('information/set-current/:id')
  async setAsCurrentVersion(@Param('id') id: string) {
    return await this.adminService.setAsCurrentVersion(id);
  }

}
