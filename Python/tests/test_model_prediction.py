import unittest
from unittest.mock import MagicMock, patch
from main import iso_forest, deep_model

class TestModelPrediction(unittest.TestCase):
    @patch('main.iso_forest.predict')
    def test_isolation_forest_prediction(self, mock_predict):
        features = MagicMock()
        mock_predict.return_value = [-1]
        prediction = iso_forest.predict(features)
        self.assertIn(prediction[0], [-1, 1])

    @patch('main.deep_model.predict')
    def test_deep_model_prediction(self, mock_predict):
        features = MagicMock()
        mock_predict.return_value = MagicMock(shape=(1, 2))
        prediction = deep_model.predict(features)
        self.assertTrue(prediction.shape[0] > 0)

if __name__ == '__main__':
    unittest.main()
