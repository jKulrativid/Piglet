package main

import (
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

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
	Pps        float64
	Mbps       float64
	DurationNs int
	Count      int
	Raw        string
	Status     Status
	Err        error
}

var database map[string]*PerfResult

func runPerf(id string, ethIface string, pktlen, pktcnt, timeout string) {
	database[id] = &PerfResult{Status: PerfRunning}
	cmd := `-c "./perf-sniffer enx2887ba3e44aa \"\" 70 100 0 0 10"`
	c := exec.Command("bash", strings.Fields(cmd)...)
	out, err := c.CombinedOutput()
	if err != nil {
		fmt.Println(string(out[:]))
		fmt.Println(c.Path, c.Args)
		log.Fatal(err)
		database[id] = &PerfResult{
			Status: PerfErr,
			Err:    err,
		}
		return
	}

	outraw := string(out[:])

	result := &PerfResult{}

	lines := strings.Split(strings.ReplaceAll(outraw, "\r\n", "\n"), "\n")
	for _, line := range lines {
		if strings.Contains(line, "Mbps") {
			re := regexp.MustCompile(`^Throughput:\s*(\d+)\s*Mbps$`)
			match := re.FindStringSubmatch(line)
			mbps, err := strconv.Atoi(match[0])
			if err != nil {
				result.Status = PerfErr
				result.Err = err
				return
			}
			result.Mbps = float64(mbps)
		} else if strings.Contains(line, "pps") {
			re := regexp.MustCompile(`^Packet per second:\s*(\d+)\s*pps$`)
			match := re.FindStringSubmatch(line)
			pps, err := strconv.Atoi(match[0])
			if err != nil {
				result.Status = PerfErr
				result.Err = err
				return
			}
			result.Pps = float64(pps)
		} else if strings.Contains(line, "pkt1 count") {
			re := regexp.MustCompile(`^overall pkt1 count = \s*(\d+)\s*$s`)
			match := re.FindStringSubmatch(line)
			cnt, err := strconv.Atoi(match[0])
			if err != nil {
				result.Status = PerfErr
				result.Err = err
				return
			}
			result.Count = cnt
		} else if strings.Contains(line, "Duration") {
			re := regexp.MustCompile(`^Duration:\s*\S+\s*s,\s*(\d+)\s*ns$`)
			match := re.FindStringSubmatch(line)
			ns, err := strconv.Atoi(match[0])
			if err != nil {
				result.Status = PerfErr
				result.Err = err
				return
			}
			result.DurationNs = ns
		}
	}

	result.Raw = outraw
	result.Status = PerfFinished
	result.Err = nil

	database[id] = result
}

func runPerfAsync(c *gin.Context) {
	uuid, err := uuid.NewV4()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err,
		})
		return
	}

	ethInterface, ok := c.GetQuery("eth")
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "query param 'eth' required",
		})
		return
	}

	pktLen, ok := c.GetQuery("pktlen")
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "query param 'pktlen' required",
		})
		return
	}

	pktCnt, ok := c.GetQuery("pktcnt")
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "query param 'pktcnt' required",
		})
		return
	}

	timeout, ok := c.GetQuery("timeout")
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "query param 'timeout' required",
		})
		return
	}

	go runPerf(uuid.String(), ethInterface, pktLen, pktCnt, timeout)

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
