package intra
import "github.com/celzero/firestack/intra/ipn"
const (
	RetrierStrategy int = 0
	DesyncStrategy int = 1
)
func SwitchStrategy(s int){
	ipn.SwitchStrategy(s)
}