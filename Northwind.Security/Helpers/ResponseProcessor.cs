using Northwind.Security.Models;
using System.Threading.Tasks;

namespace Northwind.Security.Helpers
{
    public static class ResponseProcessor
    {
        public static ProcessedResponse GetSuccessResponse(object entity = null)
        {
            return new ProcessedResponse
            {
                IsSuccessful = true,
                Message = "The operation was succesful",
                Object = entity
            };
        }

        public static ProcessedResponse GetValidationErrorResponse(string errorMessage)
        {
            ProcessedResponse response = new ProcessedResponse()
            {
                Message = errorMessage,
                IsSuccessful = false
            };

            return response;
        }

        public static ProcessedResponse GetRecordNotFoundResponse(string message = "The requested record(s) could not be found")
        {
            ProcessedResponse response = new ProcessedResponse()
            {
                Message = message,
                IsSuccessful = false
            };

            return response;
        }

    }
}
