import { Injectable, Logger } from '@nestjs/common';
import { Console } from 'console';
import * as fs from 'fs';
import * as path from 'path';

@Injectable()
export class EmailService {
    private readonly emailFilePath: string;

    constructor() {
        this.emailFilePath = path.join(process.cwd(), 'src', 'config', 'email.json');
    }

    loadEmailData(): any {
        try {
            const emailData = fs.readFileSync(this.emailFilePath, 'utf8');
            return JSON.parse(emailData);
        } catch (error) {
            Logger.error('Error al cargar la configuración:', error);
            return { maxLoginAttempts: 5 }; 
        }
    }

    saveEmailData(emailData: any): void {
        try {
            fs.writeFileSync(this.emailFilePath, JSON.stringify(emailData, null, 2));
            Logger.log('Mensaje del correo guardado exitosamente.');
        } catch (error) {
            Logger.error('Error al guardar el contenido del correo:', error);
        }
    }
    
}
