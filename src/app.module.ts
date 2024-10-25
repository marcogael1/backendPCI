import { AppConfigModule } from './services/appconfig.module';
import { LogsModule } from './services/logs.module';
import { EmailService } from './services/email.service';
import { IncidentMonitorService } from './incidentMonitor/incidentmonitor.service';
import { IncidentMonitorModule } from './incidentMonitor/incidentmonitor.module';
import { CompanyProfileModule } from './companyProfile/companyprofile.module';
import { Module, MiddlewareConsumer, NestModule, RequestMethod } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { ConfigModule } from '@nestjs/config';
import { ThrottlerModule, ThrottlerGuard } from '@nestjs/throttler';
import { RegisterModule } from './register/register.module';
import { AdminModule } from './admin/admin.module';
import { AuthModule } from './auth/auth.module';
import { CorsMiddleware } from './cors.middleware';
import { APP_GUARD } from '@nestjs/core';
@Module({
  imports: [
    AppConfigModule, 
    ConfigModule, 
    LogsModule, 
    IncidentMonitorModule,
    CompanyProfileModule,
    ConfigModule.forRoot({
      isGlobal: true,
    }),
    MongooseModule.forRoot(process.env.MONGODB_URI),
    ThrottlerModule.forRoot([{
      ttl: 1000,
      limit: 10,
    }]),
    RegisterModule,
    AdminModule,
    AuthModule,
    CompanyProfileModule,
  ],
  providers: [
        EmailService, 
    IncidentMonitorService,
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard,
    },
  ],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer
      .apply(CorsMiddleware)
      .forRoutes({ path: '*', method: RequestMethod.ALL });
  }
}
