import { ExecutionContext, createParamDecorator } from "@nestjs/common";
//tener en cuenta
export const GetCurrentUser = createParamDecorator(
    (data: string | undefined, context: ExecutionContext) => {
        const request = context.switchToHttp().getRequest()
        if (!data) return request.user;
        return request.user[data];
    }
)