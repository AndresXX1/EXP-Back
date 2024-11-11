import { IsNotEmpty } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class LogInWithGoogleDto {
  @ApiProperty({ example: 'asdasdasdasdsadasd', description: 'Google token' })
  @IsNotEmpty({ message: 'Introduce tu cuenta de google.' })
  token: string;

  tokenNotifications: string;
}
