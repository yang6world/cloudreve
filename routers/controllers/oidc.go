package controllers

import (
	"net/http"

	"github.com/cloudreve/Cloudreve/v4/pkg/serializer"
	oidcsvc "github.com/cloudreve/Cloudreve/v4/service/oidc"
	"github.com/gin-gonic/gin"
)

func OIDCStart(c *gin.Context) {
	target, err := oidcsvc.Start(c)
	if err != nil {
		c.JSON(http.StatusOK, serializer.Err(c, err))
		return
	}
	c.Redirect(http.StatusFound, target)
}

func OIDCCallback(c *gin.Context) {
	c.Redirect(http.StatusFound, oidcsvc.Callback(c))
}

func OIDCExchange(c *gin.Context) {
	service := ParametersFromContext[*oidcsvc.ExchangeService](c, oidcsvc.ExchangeParameterCtx{})
	response, err := service.Exchange(c)
	if err != nil {
		c.JSON(http.StatusOK, serializer.Err(c, err))
		return
	}
	c.JSON(http.StatusOK, serializer.Response{Data: response})
}
