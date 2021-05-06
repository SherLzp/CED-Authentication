package controllers

import (
	"encoding/json"
	"github.com/beego/beego/v2/server/web"
)

const (
	SUCCESS    = 200
	ERROR      = 500
	PARSEERROR = 501
)

// General Response Data
type SuperResult struct {
	Status  int         `json:"status"`
	Data    interface{} `json:"data"`
	Message string      `json:"msg"`
}

type BaseController struct {
	web.Controller
}

func (c *BaseController) RequestBody() []byte {
	return c.Ctx.Input.RequestBody
}

func (c *BaseController) decodeRawRequestBodyJson() map[string]interface{} {
	var mm interface{}
	requestBody := make(map[string]interface{})
	json.Unmarshal(c.RequestBody(), &mm)
	if mm != nil {
		var m1 map[string]interface{}
		m1 = mm.(map[string]interface{})
		for k, v := range m1 {
			requestBody[k] = v
		}
	}
	return requestBody
}

func (c *BaseController) Get() {
	c.Ctx.WriteString("Welcome to auth protocol!")
}

func (c *BaseController) JsonData() map[string]interface{} {
	return c.decodeRawRequestBodyJson()
}

// response parse request data error
func (c *BaseController) ResParseError(err error) {
	c.Error(PARSEERROR, "the format of request data is wrong！", err)
}

// response when error
func (c *BaseController) Error(status int, msg string, err error) {
	result := SuperResult{
		Status:  status,
		Message: msg,
	}
	c.ResJson(result)
}

// response when succeed
func (c *BaseController) Success(data interface{}, msg string) {
	result := SuperResult{
		Status:  SUCCESS,
		Data:    data,
		Message: msg,
	}
	c.ResJson(result)
}

// response json data
func (c *BaseController) ResJson(v interface{}) {
	c.Data["json"] = v
	c.ServeJSON()
}
