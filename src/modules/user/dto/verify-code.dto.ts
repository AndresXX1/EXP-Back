import { IsString, Length } from 'class-validator';

export class VerifyCodeDto {
  @Length(5, 5, { message: 'El codigo debe ser de cinco cifras.' })
  @IsString()
  code: string;
}
