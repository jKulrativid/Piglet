package main

import (
	"fmt"
	"net/http"
	"os/exec"

	"github.com/fatih/structs"
	"github.com/gin-gonic/gin"
	uuid "github.com/nu7hatch/gouuid"
)

type Status int

const (
	PerfRunning  = 1
	PerfErr      = 2
	PerfFinished = 3
)

type PerfResult struct {
	Pps      float64
	Mbps     float64
	Duration float64
	Count    int
	Status   Status
	Err      error
}

var database map[string]*PerfResult

func runPerf(id string, ethIface string, pktlen int, pktcnt int) {
	database[id] = &PerfResult{Status: PerfRunning}

	cmdText := fmt.Sprintf("./perf-sniffer %s \"\" %d %d 0 0", ethIface, pktlen, pktcnt)
	out, err := exec.Command(cmdText).Output()
	if err != nil {
		database[id] = &PerfResult{
			Status: PerfErr,
			Err:    err,
		}
		return
	}

	database[id] = &PerfResult{
		Pps:      1.2,
		Mbps:     3.4,
		Duration: 4.5,
		Count:    888,
		Status:   PerfFinished,
		Err:      nil,
	}
}

func runPerfAsync(c *gin.Context) {
	uuid, err := uuid.NewV4()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err,
		})
	}

	go runPerf(uuid.String(), "eth0", 1, 1)

	c.JSON(http.StatusOK, gin.H{
		"id": uuid.String(),
	})
}

func queryResult(c *gin.Context) {
	id := c.Query("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "required query param 'id' not found",
		})
		return
	}

	result := database[id]
	if result == nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("result of perf ID=%s not found", id),
		})
		return
	}

	c.JSON(http.StatusOK, structs.Map(result))
}

func main() {
	database = make(map[string]*PerfResult)

	r := gin.Default()

	r.GET("/perf", runPerfAsync)
	r.GET("/result", queryResult)

	r.Run(":8080")
}
