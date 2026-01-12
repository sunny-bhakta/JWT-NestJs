import { ExecutionContext, Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { TokenExpiredError } from 'jsonwebtoken';
import { TokenErrorException } from './errors/token-error.exception';
import { TokenEventsService } from './token-events.service';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
	constructor(private readonly tokenEvents: TokenEventsService) {
		super();
	}

		handleRequest(err: unknown, user: any, info?: Error, context?: ExecutionContext) {
		if (user) {
			return user;
		}

		if (info) {
			throw this.mapPassportInfoToException(info, context ?? this.contextRef);
		}

			if (err) {
				if (err instanceof TokenErrorException) {
					this.logFailure(err.code, err.message, context ?? this.contextRef);
					throw err;
				}
				const exception = new TokenErrorException('ACCESS_TOKEN_INVALID');
				this.logFailure(exception.code, err instanceof Error ? err.message : 'Unknown passport error', context ?? this.contextRef);
				throw exception;
		}

			const exception = new TokenErrorException('ACCESS_TOKEN_MISSING');
			this.logFailure(exception.code, 'No authentication token was provided', context ?? this.contextRef);
			throw exception;
	}

		private contextRef?: ExecutionContext;

		async canActivate(context: ExecutionContext) {
			this.contextRef = context;
			return (super.canActivate(context) as Promise<boolean>)
				.finally(() => {
					this.contextRef = undefined;
				});
		}

		private mapPassportInfoToException(info: Error, context?: ExecutionContext) {
		if (info instanceof TokenErrorException) {
			return info;
		}

		const message = info.message ?? '';
		if (info instanceof TokenExpiredError || info.name === 'TokenExpiredError') {
				const exception = new TokenErrorException('ACCESS_TOKEN_EXPIRED');
				this.logFailure(exception.code, message, context);
				return exception;
		}

		if (message.includes('No auth token') || message.includes('jwt must be provided')) {
				const exception = new TokenErrorException('ACCESS_TOKEN_MISSING');
				this.logFailure(exception.code, message, context);
				return exception;
		}

			const exception = new TokenErrorException('ACCESS_TOKEN_INVALID');
			this.logFailure(exception.code, message, context);
			return exception;
	}

		private logFailure(code: string, reason: string, context?: ExecutionContext) {
			const request = context?.switchToHttp().getRequest();
			this.tokenEvents.logAccessTokenFailure({ code, reason, request });
		}
}
