namespace TodoApi.Filters;

public class ValidationFilter<T> : IRouteHandlerFilter where T : class
{
    
    public async ValueTask<object?> InvokeAsync(RouteHandlerInvocationContext context, RouteHandlerFilterDelegate next)
    {
        var param = context.Parameters.FirstOrDefault(x => x?.GetType() == typeof(T));

        if(param is null)
        {
            return Results.BadRequest();
        }

        if (param is Item)
        {
            var validationResult = IsValidItem(param as Item);
            
            if(!validationResult)
            {
                return Results.BadRequest("Invalid parameters.");
            }
        }

        // before the endpoint call
        var result = await next(context);

        // after endpoint call
        return result;
    }

    bool IsValidItem(Item? item)
    {
        if (item == null)
            return false;
        
        if (item.Title.Length > 1 && item.Id > 0)
            return true;

        return false;
    }
}
