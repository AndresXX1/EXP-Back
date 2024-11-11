import { IsNotEmpty, IsString } from 'class-validator';

export class ForgetPasswordCodeDto {
  @IsString()
  @IsNotEmpty({ message: 'Introduce un token.' })
  token: string;

  @IsString()
  @IsNotEmpty({ message: 'Introduce un codigo.' })
  code: string;
}
