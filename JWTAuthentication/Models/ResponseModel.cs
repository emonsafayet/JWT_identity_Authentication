using JWTAuthentication.Enums;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace JWTAuthentication.Models
{
    public class ResponseModel
    {
        public ResponseCode ResponseCode { get; set; }
        public string ResponseMessage { get; set; }
        public object DataSet { get; set; }

        public ResponseModel(ResponseCode responseCode, string responseMessage, object dataSet)
        {
            ResponseCode = responseCode;
            ResponseMessage = responseMessage;
            DataSet = dataSet;
        }
    }
}
