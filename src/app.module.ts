import { AdminModule } from './admin/admin.module';
import { Module, MiddlewareConsumer, NestModule, RequestMethod  } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { AuthModule } from './auth/auth.module';
import { CorsMiddleware } from './cors.middleware';
@Module({
  imports: [
        AdminModule, 
    MongooseModule.forRoot('mongodb://localhost:27017/pciDataBase'),
    AuthModule,
    AdminModule
  ],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer
      .apply(CorsMiddleware)
      .forRoutes({ path: '*', method: RequestMethod.ALL });
  }
}