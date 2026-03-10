mod crypto_analysis;

use pyo3::prelude::*;
use pyo3::types::PyBytes;

#[pyfunction]
fn parse_zip_bytes(py: Python, data: &Bound<'_, PyBytes>) -> PyResult<String> {
    let bytes = data.as_bytes();
    match crypto_analysis::parse_zip_bytes(bytes) {
        Ok(features) => {
            let json = serde_json::to_string(&features)
                .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
            Ok(json)
        }
        Err(e) => Err(pyo3::exceptions::PyValueError::new_err(e)),
    }
}

#[pyfunction]
fn extract_crypto_features(py: Python, data: &Bound<'_, PyBytes>) -> PyResult<String> {
    let bytes = data.as_bytes();
    let features = crypto_analysis::extract_crypto_features(bytes);
    let json = serde_json::to_string(&features)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
    Ok(json)
}

#[pyfunction]
fn compute_entropy(py: Python, data: &Bound<'_, PyBytes>) -> PyResult<f64> {
    let bytes = data.as_bytes();
    Ok(crypto_analysis::compute_shannon_entropy(bytes))
}

#[pymodule]
fn crypto_rs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(parse_zip_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(extract_crypto_features, m)?)?;
    m.add_function(wrap_pyfunction!(compute_entropy, m)?)?;
    Ok(())
}
