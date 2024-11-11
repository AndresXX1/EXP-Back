import { IsNotEmpty, IsDate, IsPhoneNumber } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { registerDecorator, ValidationArguments, ValidationOptions } from 'class-validator';
import { subYears } from 'date-fns';

// Validador personalizado para asegurarse de que el usuario tenga al menos 18 años
export function IsAdult(validationOptions?: ValidationOptions) {
  return function (target: any, propertyName: string) {
    registerDecorator({
      name: 'isAdult',
      target: target.constructor,
      propertyName: propertyName,
      options: validationOptions,
      validator: {
        validate(value: Date) {
          const today = new Date();
          const date18YearsAgo = subYears(today, 18); // resta 18 años a la fecha actual
          return value <= date18YearsAgo; // Verifica si la fecha de nacimiento es menor o igual a la fecha de hace 18 años
        },
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        defaultMessage(args: ValidationArguments) {
          return 'Debes tener al menos 18 años para registrarte.';
        },
      },
    });
  };
}

export class UpdateSecondDataDto {
  @ApiProperty({ example: '1989-05-24', description: 'Fecha de nacimiento' })
  @IsDate({ message: 'Introduce una fecha válida.' })
  @IsNotEmpty({ message: 'Introduce una fecha de nacimiento.' })
  @IsAdult({ message: 'Debes tener al menos 18 años para registrarte.' })
  birthday: Date;

  @ApiProperty({ example: '1123456789', description: 'Número de teléfono' })
  @IsPhoneNumber('AR', { message: 'Introduce un número de teléfono válido para Argentina.' })
  @IsNotEmpty({ message: 'Introduce un número de teléfono.' })
  phone: string;
}
