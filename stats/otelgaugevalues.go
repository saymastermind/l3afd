package stats

import (
	"sync"

	"go.opentelemetry.io/otel/attribute"
	api "go.opentelemetry.io/otel/metric"
)

// =====================================================
type OtelMetricAttributes struct {
	baseAttribsCount	int
	mutex 				sync.RWMutex
	
	MetricName			string
	Attribs 			[]attribute.KeyValue
}

func newOtelMetricAttribs(metricName string, baseAttribs []attribute.KeyValue) *OtelMetricAttributes {
	retval := OtelMetricAttributes {
		MetricName: metricName,
		baseAttribsCount: len(baseAttribs),
		Attribs: make([]attribute.KeyValue, len(baseAttribs) + 5),
	}

	copy(retval.Attribs, baseAttribs)
	retval.Attribs = retval.Attribs[0:len(baseAttribs)]

	return &retval
}

func (otelMetricAttribs *OtelMetricAttributes) GetMeasurementOptions() api.MeasurementOption {
	otelMetricAttribs.mutex.RLock()
	defer otelMetricAttribs.mutex.RUnlock()

	return api.WithAttributes(otelMetricAttribs.Attribs...)
}

func (otelMetricAttribs *OtelMetricAttributes) SetAttributes(attribValues map[string]string) {
	otelMetricAttribs.mutex.Lock()
	defer otelMetricAttribs.mutex.Unlock()

	otelMetricAttribs.Attribs = otelMetricAttribs.Attribs[:otelMetricAttribs.baseAttribsCount]
	for name, value := range attribValues {
		otelMetricAttribs.Attribs = append(otelMetricAttribs.Attribs, attribute.Key(name).String(value))
	}
}

func (otelMetricAttributes *OtelMetricAttributes) GetAttributes() []attribute.KeyValue {
	otelMetricAttributes.mutex.RLock()
	defer otelMetricAttributes.mutex.RUnlock()

	return otelMetricAttributes.Attribs
}

// =====================================================
type OtelGaugeValue struct {
	Value 					float64
	*OtelMetricAttributes
}

func NewGaugeValue(metricName string, baseAttribs []attribute.KeyValue) *OtelGaugeValue {
	return &OtelGaugeValue {
		Value: 0,
		OtelMetricAttributes: newOtelMetricAttribs(metricName, baseAttribs),
	}
}

func (gaugeValue *OtelGaugeValue) GetValue() float64 {
	gaugeValue.mutex.RLock()
	defer gaugeValue.mutex.RUnlock()

	return gaugeValue.Value
}

func (gaugeValue *OtelGaugeValue) SetValue(val float64) {
	gaugeValue.mutex.Lock()
	defer gaugeValue.mutex.Unlock()
	
	gaugeValue.Value = val
} 

// =====================================================
type OtelCounterValue struct {
	Value 					int64
	*OtelMetricAttributes
}

func NewCounterValue(metricName string, baseAttribs []attribute.KeyValue) *OtelCounterValue {
	return &OtelCounterValue{
		Value: 1,
		OtelMetricAttributes: newOtelMetricAttribs(metricName, baseAttribs),
	}
}

func (counterValue *OtelCounterValue) GetValue() int64 {
	counterValue.mutex.RLock()
	defer counterValue.mutex.Unlock()

	return counterValue.Value
}
