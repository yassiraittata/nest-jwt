import { createParamDecorator, ExecutionContext } from '@nestjs/common';

export const CurrentUser = createParamDecorator(
  (data: string | undefined, context: ExecutionContext) => {
    const request = context.switchToHttp().getRequest();

    console.log('current user decorator', request.user);

    if (!data) return request.user;
    return request.user[data];
  },
);
