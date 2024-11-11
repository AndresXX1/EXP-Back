import { ExceptionFilter, Catch, ArgumentsHost, HttpException, HttpStatus, Logger, BadRequestException } from '@nestjs/common';
import { Request, Response } from 'express';

interface CustomException {
  message: string | string[];
  statusCode: number;
  error: string;
}

@Catch()
export class HttpExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger(HttpExceptionFilter.name);
  constructor() {}

  catch(exception: unknown, host: ArgumentsHost): void {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();

    this.logger.error(exception);
    const status = exception instanceof HttpException ? exception.getStatus() : HttpStatus.INTERNAL_SERVER_ERROR;
    const raisedExceptionResponse = (
      exception instanceof HttpException
        ? exception.getResponse()
        : {
            message: 'Internal server error',
            statusCode: status,
            error: 'InternalServerError',
          }
    ) as CustomException;

    let message = typeof raisedExceptionResponse === 'string' ? raisedExceptionResponse : raisedExceptionResponse.message;
    const error = raisedExceptionResponse['error'] || 'InternalServerError';
    const path = request.path;

    if (exception instanceof BadRequestException && Array.isArray(message)) {
      message = message[0]; // Solo tomar el primer mensaje de error
    }

    response.status(status).json({
      ok: false,
      message: message,
      statusCode: status,
      error,
      path,
    });
  }
}
