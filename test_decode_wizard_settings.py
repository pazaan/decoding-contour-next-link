import unittest
from .read_minimed_next24 \
    import PumpBolusWizardCarbRatiosResponseMessage, PumpBolusWizardSensitivityFactorsResponseMessage, PumpBolusWizardBGTargetsResponseMessage

from datetime import datetime, time

class TestBolusWizardSettingsDecode(unittest.TestCase):

    def test_PumpBolusWizardCarbRatiosResponseMessage(self):
        example = '03012C2E7007000000000000019000000000000000044C0B000000000000044C11000000000000044C13000000000000028A1600000000000001F41E00000000000001F424'
        example_binary = bytearray.fromhex(example)

        testobj = PumpBolusWizardCarbRatiosResponseMessage()
        testobj.responsePayload = example_binary

        self.assertEqual(testobj.wholePayloadHex, example)
        self.assertEqual(testobj.recordCount, 7)

        self.assertEqual(testobj.CarbRatio(0), 0.4)
        self.assertEqual(testobj.StartTime(0), time(0, 0))
        self.assertEqual(testobj.EndTime(0), time(5, 30))

        self.assertEqual(testobj.CarbRatio(1), 1.1)
        self.assertEqual(testobj.StartTime(1), time(5, 30))
        self.assertEqual(testobj.EndTime(1), time(8, 30))

        self.assertEqual(testobj.CarbRatio(2), 1.1)
        self.assertEqual(testobj.StartTime(2), time(8, 30))
        self.assertEqual(testobj.EndTime(2), time(9, 30))

        self.assertEqual(testobj.CarbRatio(3), 1.1)
        self.assertEqual(testobj.StartTime(3), time(9, 30))
        self.assertEqual(testobj.EndTime(3), time(11, 00))

        self.assertEqual(testobj.CarbRatio(4), 0.65)
        self.assertEqual(testobj.StartTime(4), time(11, 00))
        self.assertEqual(testobj.EndTime(4), time(15, 0))

        self.assertEqual(testobj.CarbRatio(5), 0.5)
        self.assertEqual(testobj.StartTime(5), time(15, 0))
        self.assertEqual(testobj.EndTime(5), time(18, 0))

        self.assertEqual(testobj.CarbRatio(6), 0.5)
        self.assertEqual(testobj.StartTime(6), time(18, 0))
        self.assertEqual(testobj.EndTime(6), time.max)

        self.assertDictEqual(testobj.FullConfiguration, {
            "count": 7,
            "records": [
                {
                    "starttime": time(0, 0),
                    "endtime": time(5, 30),
                    "ratio": 0.4
                },
                {
                    "starttime": time(5, 30),
                    "endtime": time(8, 30),
                    "ratio": 1.1
                },
                {
                    "starttime": time(8, 30),
                    "endtime": time(9, 30),
                    "ratio": 1.1
                },
                {
                    "starttime": time(9, 30),
                    "endtime": time(11, 0),
                    "ratio": 1.1
                },
                {
                    "starttime": time(11, 0),
                    "endtime": time(15, 0),
                    "ratio": 0.65
                },
                {
                    "starttime": time(15, 0),
                    "endtime": time(18, 0),
                    "ratio": 0.5
                },
                {
                    "starttime": time(18, 0),
                    "endtime": time.max,
                    "ratio": 0.5
                },
            ]
        })

    def test_PumpBolusWizardSensitivityFactorsResponseMessage(self):
        example = '04012F1AB7050096005300007800430C00640038140078004324008C004E2E'
        example_binary = bytearray.fromhex(example)

        testobj = PumpBolusWizardSensitivityFactorsResponseMessage()
        testobj.responsePayload = example_binary

        self.assertEqual(testobj.wholePayloadHex, example)
        self.assertEqual(testobj.recordCount, 5)

        self.assertEqual(testobj.FactorMgDl(0), 150)
        self.assertEqual(testobj.FactorMmolL(0), 83)
        self.assertEqual(testobj.StartTime(0), time(0, 0))
        self.assertEqual(testobj.EndTime(0), time(6, 00))

        self.assertEqual(testobj.FactorMgDl(1), 120)
        self.assertEqual(testobj.FactorMmolL(1), 67)
        self.assertEqual(testobj.StartTime(1), time(6, 00))
        self.assertEqual(testobj.EndTime(1), time(10, 00))

        self.assertEqual(testobj.FactorMgDl(2), 100)
        self.assertEqual(testobj.FactorMmolL(2), 56)
        self.assertEqual(testobj.StartTime(2), time(10, 00))
        self.assertEqual(testobj.EndTime(2), time(18, 00))

        self.assertEqual(testobj.FactorMgDl(3), 120)
        self.assertEqual(testobj.FactorMmolL(3), 67)
        self.assertEqual(testobj.StartTime(3), time(18, 00))
        self.assertEqual(testobj.EndTime(3), time(23, 00))

        self.assertEqual(testobj.FactorMgDl(4), 140)
        self.assertEqual(testobj.FactorMmolL(4), 78)
        self.assertEqual(testobj.StartTime(4), time(23, 00))
        self.assertEqual(testobj.EndTime(4), time.max)

        self.assertDictEqual(testobj.FullConfiguration, {
            "count": 5,
            "records": [
                {
                    "starttime": time(0, 0),
                    "endtime": time(6, 00),
                    "factorMgDl": 150,
                    "factorMmolL": 83,
                },
                {
                    "starttime": time(6, 00),
                    "endtime": time(10, 00),
                    "factorMgDl": 120,
                    "factorMmolL": 67,
                },
                {
                    "starttime": time(10, 00),
                    "endtime": time(18, 00),
                    "factorMgDl": 100,
                    "factorMmolL": 56,
                },
                {
                    "starttime": time(18, 00),
                    "endtime": time(23, 0),
                    "factorMgDl": 120,
                    "factorMmolL": 67,
                },
                {
                    "starttime": time(23, 0),
                    "endtime": time.max,
                    "factorMgDl": 140,
                    "factorMmolL": 78,
                },
            ]
        })

    def test_PumpBolusWizardBGTargetsResponseMessage(self):
        example = '050132D1E10400780043005A003200007800430050002C0A007800430050002C1000780043005A003224'
        example_binary = bytearray.fromhex(example)

        testobj = PumpBolusWizardBGTargetsResponseMessage()
        testobj.responsePayload = example_binary

        self.assertEqual(testobj.wholePayloadHex, example)
        self.assertEqual(testobj.recordCount, 4)

        self.assertEqual(testobj.LowTargetMgDl(0), 90)
        self.assertEqual(testobj.HighTargetMgDl(0), 120)
        self.assertEqual(testobj.LowTargetMmolL(0), 50)
        self.assertEqual(testobj.HighTargetMmolL(0), 67)
        self.assertEqual(testobj.StartTime(0), time(0, 0))
        self.assertEqual(testobj.EndTime(0), time(5, 00))

        self.assertEqual(testobj.LowTargetMgDl(1), 80)
        self.assertEqual(testobj.HighTargetMgDl(1), 120)
        self.assertEqual(testobj.LowTargetMmolL(1), 44)
        self.assertEqual(testobj.HighTargetMmolL(1), 67)
        self.assertEqual(testobj.StartTime(1), time(5, 0))
        self.assertEqual(testobj.EndTime(1), time(8, 00))

        self.assertEqual(testobj.LowTargetMgDl(2), 80)
        self.assertEqual(testobj.HighTargetMgDl(2), 120)
        self.assertEqual(testobj.LowTargetMmolL(2), 44)
        self.assertEqual(testobj.HighTargetMmolL(2), 67)
        self.assertEqual(testobj.StartTime(2), time(8, 0))
        self.assertEqual(testobj.EndTime(2), time(18, 00))

        self.assertEqual(testobj.LowTargetMgDl(3), 90)
        self.assertEqual(testobj.HighTargetMgDl(3), 120)
        self.assertEqual(testobj.LowTargetMmolL(3), 50)
        self.assertEqual(testobj.HighTargetMmolL(3), 67)
        self.assertEqual(testobj.StartTime(3), time(18, 0))
        self.assertEqual(testobj.EndTime(3), time.max)

        self.assertDictEqual(testobj.FullConfiguration, {
            "count": 4,
            "records": [
                {
                    "starttime": time(0, 0),
                    "endtime": time(5, 00),
                    "lowTargetMgDl": 90,
                    "lowTargetMmolL": 50,
                    "highTargetMgDl": 120,
                    "highTargetMmolL": 67,
                },
                {
                    "starttime": time(5, 00),
                    "endtime": time(8, 00),
                    "lowTargetMgDl": 80,
                    "lowTargetMmolL": 44,
                    "highTargetMgDl": 120,
                    "highTargetMmolL": 67,
                },
                {
                    "starttime": time(8, 00),
                    "endtime": time(18, 00),
                    "lowTargetMgDl": 80,
                    "lowTargetMmolL": 44,
                    "highTargetMgDl": 120,
                    "highTargetMmolL": 67,
                },
                {
                    "starttime": time(18, 00),
                    "endtime": time.max,
                    "lowTargetMgDl": 90,
                    "lowTargetMmolL": 50,
                    "highTargetMgDl": 120,
                    "highTargetMmolL": 67,
                },
            ]
        })

if __name__ == '__main__':
    unittest.main()