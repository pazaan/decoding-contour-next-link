import unittest
from decoding_contour_next_link \
    import PumpBolusWizardCarbRatiosResponseMessage, PumpBolusWizardSensitivityFactorsResponseMessage, PumpBolusWizardBGTargetsResponseMessage

from datetime import time

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

        self.assertEquals(testobj.CarbRatio(1), 1.1)
        self.assertEquals(testobj.StartTime(1), time(5, 30))

        self.assertEquals(testobj.CarbRatio(2), 1.1)
        self.assertEquals(testobj.StartTime(2), time(8, 30))

        self.assertEquals(testobj.CarbRatio(3), 1.1)
        self.assertEquals(testobj.StartTime(3), time(9, 30))

        self.assertEquals(testobj.CarbRatio(4), 0.65)
        self.assertEquals(testobj.StartTime(4), time(11, 00))

        self.assertEquals(testobj.CarbRatio(5), 0.5)
        self.assertEquals(testobj.StartTime(5), time(15, 0))

        self.assertEquals(testobj.CarbRatio(6), 0.5)
        self.assertEquals(testobj.StartTime(6), time(18, 0))

if __name__ == '__main__':
    unittest.main()