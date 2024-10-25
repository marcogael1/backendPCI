import { Module } from '@nestjs/common';
import { IncidentMonitorService } from './incidentmonitor.service';
import { IncidentsController } from './incidentmonitor.controller';
import { LogsModule } from '../services/logs.module'; // Importa LogsModule
@Module({
    imports: [
        LogsModule,
    ],
    controllers: [IncidentsController],
    providers: [IncidentMonitorService],
    exports: [IncidentMonitorService],  
})
export class IncidentMonitorModule { }
