import unittest
from decoding_contour_next_link \
    import PumpBolusWizardCarbRatiosResponseMessage, PumpBolusWizardSensitivityFactorsResponseMessage, PumpBolusWizardBGTargetsResponseMessage

from datetime import datetime, time

class TestBolusWizardSettingsDecode(unittest.TestCase):

    def test_PumpBolusWizardCarbRatiosResponseMessage(self):
        example = '03012C2E7007000000000000019000000000000000044C0B000000000000044C11000000000000044C13000000000000028A1600000000000001F41E00000000000001F424'
        example_binary = bytearray.fromhex(example)

        testobj = PumpBolusWizardCarbRatiosResponseMessage()
        testobj.responsePayload = example_binary

        self.assertEquals(testobj.wholePayloadHex, example)
        self.assertEquals(testobj.recordCount, 7)

        self.assertEquals(testobj.CarbRatio(0), 0.4)
        self.assertEquals(testobj.StartTime(0), time(0, 0))
        self.assertEquals(testobj.EndTime(0), time(5, 30))

        self.assertEquals(testobj.CarbRatio(1), 1.1)
        self.assertEquals(testobj.StartTime(1), time(5, 30))
        self.assertEquals(testobj.EndTime(1), time(8, 30))

        self.assertEquals(testobj.CarbRatio(2), 1.1)
        self.assertEquals(testobj.StartTime(2), time(8, 30))
        self.assertEquals(testobj.EndTime(2), time(9, 30))

        self.assertEquals(testobj.CarbRatio(3), 1.1)
        self.assertEquals(testobj.StartTime(3), time(9, 30))
        self.assertEquals(testobj.EndTime(3), time(11, 00))

        self.assertEquals(testobj.CarbRatio(4), 0.65)
        self.assertEquals(testobj.StartTime(4), time(11, 00))
        self.assertEquals(testobj.EndTime(4), time(15, 0))

        self.assertEquals(testobj.CarbRatio(5), 0.5)
        self.assertEquals(testobj.StartTime(5), time(15, 0))
        self.assertEquals(testobj.EndTime(5), time(18, 0))

        self.assertEquals(testobj.CarbRatio(6), 0.5)
        self.assertEquals(testobj.StartTime(6), time(18, 0))
        self.assertEquals(testobj.EndTime(6), time.max)

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

if __name__ == '__main__':
    unittest.main()