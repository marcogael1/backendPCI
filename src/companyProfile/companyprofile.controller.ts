import { Controller, Get, Post, Put, Delete, Body } from '@nestjs/common';
import { CompanyProfileService } from './companyprofile.service';

@Controller('company-profile')
export class CompanyProfileController {
  constructor(private readonly companyProfileService: CompanyProfileService) {}

  @Post()
  async create(@Body() data: any) {
    return await this.companyProfileService.create(data);
  }

  @Get()
  async findOne() {
    return await this.companyProfileService.findOne();
  }

  @Put()
  async update(@Body() data: any) {
    return await this.companyProfileService.update(data);
  }

  @Delete()
  async delete() {
    return await this.companyProfileService.delete();
  }
}
