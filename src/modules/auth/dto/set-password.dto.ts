import { IsNotEmpty, Matches } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class SetPasswordDto {
  @ApiProperty({ example: 'usuario@123456', description: 'Nueva contraseña' })
  @IsNotEmpty({ message: 'Es necesario una nueva contraseña' })
  @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[$&+,:;=?@#|'<>.^*()%!-])[A-Za-z\d@$&+,:;=?@#|'<>.^*()%!-]{8,}$/, { message: 'invalid password' })
  newPassword: string;
}
