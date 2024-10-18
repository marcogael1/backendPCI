import { Controller, Get, Post, Body, Put, Param, Delete } from '@nestjs/common';
import { AdminService } from './admin.service';

@Controller('admin')
export class AdminController {
  constructor(private readonly adminService: AdminService) {}

  @Post()
  create(@Body() body: any) {
    return this.adminService.create(body);
  }
  @Get()
  findAll() {
    return this.adminService.findAll();
  }
  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.adminService.findOne(id);
  }
  @Put(':id')
  update(@Param('id') id: string, @Body() body: any) {
    return this.adminService.update(id, body);
  }
  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.adminService.remove(id);
  }
}
